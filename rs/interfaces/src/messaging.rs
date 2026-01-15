//! Message Routing public interfaces.
use crate::{execution_environment::CanisterOutOfCyclesError, validation::ValidationError};
use ic_error_types::ErrorCode;
use ic_types::{
    CanisterId, Height, NumBytes, Time,
    batch::{Batch, ValidationContext, XNetPayload},
    consensus::Payload,
};

/// Errors that `MessageRouting` may return.
#[derive(Eq, PartialEq, Debug)]
pub enum MessageRoutingError {
    /// The batch was not delivered because the batch queue is full.
    QueueIsFull,
    /// The batch is ignored because its number is not the one we
    /// expected.
    Ignored {
        expected_height: Height,
        actual_height: Height,
    },
}

/// XNet payload validation error details.
#[derive(Debug)]
pub enum InvalidXNetPayload {
    InvalidSlice(String),
}

#[derive(Debug)]
pub enum XNetPayloadValidationFailure {
    StateNotCommittedYet(Height),
    StateRemoved(Height),
}

pub type XNetPayloadValidationError =
    ValidationError<InvalidXNetPayload, XNetPayloadValidationFailure>;

/// The public interface for the MessageRouting layer.
pub trait MessageRouting: Send + Sync {
    /// Delivers a finalized `Batch` for deterministic processing.
    ///
    /// Repeated calls with the same batch result in
    /// `MessageRoutingError::Ignored`.
    ///
    /// This function is asynchronous: it returns immediately after enqueuing
    /// the batch for processing and doesn't wait for execution of the batch to
    /// complete.
    fn deliver_batch(&self, b: Batch) -> Result<(), MessageRoutingError>;

    /// Returns the height of the next expected batch.
    fn expected_batch_height(&self) -> Height;
}

/// Interface for selecting `Streams` for inclusion into a `Payload`.
pub trait XNetPayloadBuilder: Send + Sync {
    /// Produces an `XNetPayload` of maximum byte size `byte_limit` that is
    /// valid given a `ValidationContext` (certified height plus registry
    /// version) and `past_payloads` (the `XNetPayloads` from all blocks
    /// above the certified height, in descending block height order).
    ///
    /// Returns the payload and its estimated byte size (using the same logic
    /// as `validate_xnet_payload()`).
    fn get_xnet_payload(
        &self,
        validation_context: &ValidationContext,
        past_payloads: &[&XNetPayload],
        byte_limit: NumBytes,
    ) -> (XNetPayload, NumBytes);

    /// Checks whether the provided `XNetPayload` is valid given a
    /// `ValidationContext` (certified height and registry version) and
    /// `past_payloads` (the `XNetPayloads` from all blocks above the certified
    /// height, in descending block height order).
    ///
    /// If valid, returns the payload's `CountBytes`-like byte size (estimated,
    /// deterministic, using the exact same logic that `get_xnet_payload()` uses
    /// for enforcing `byte_limit`); else returns a permanent or transient
    /// `ValidationError`.
    fn validate_xnet_payload(
        &self,
        payload: &XNetPayload,
        validation_context: &ValidationContext,
        past_payloads: &[&XNetPayload],
    ) -> Result<NumBytes, XNetPayloadValidationError>;

    /// Extracts the sequence of past `XNetPayloads` from `past_payloads`.
    fn filter_past_payloads<'a>(
        &self,
        past_payloads: &'a [(Height, Time, Payload)],
    ) -> Vec<&'a XNetPayload> {
        past_payloads
            .iter()
            .filter_map(|(_, _, payload)| {
                if payload.is_summary() {
                    None
                } else {
                    Some(&payload.as_ref().as_data().batch.xnet)
                }
            })
            .collect()
    }
}

pub const LABEL_VALUE_CANISTER_NOT_FOUND: &str = "CanisterNotFound";
pub const LABEL_VALUE_CANISTER_STOPPED: &str = "CanisterStopped";
pub const LABEL_VALUE_CANISTER_STOPPING: &str = "CanisterStopping";
pub const LABEL_VALUE_CANISTER_OUT_OF_CYCLES: &str = "CanisterOutOfCycles";
pub const LABEL_VALUE_CANISTER_METHOD_NOT_FOUND: &str = "CanisterMethodNotFound";
pub const LABEL_VALUE_SUBNET_METHOD_NOT_ALLOWED: &str = "SubnetMethodNotAllowed";
pub const LABEL_VALUE_INVALID_MANAGEMENT_PAYLOAD: &str = "InvalidManagementPayload";
pub const LABEL_VALUE_INGRESS_HISTORY_FULL: &str = "IngressHistoryFull";

#[derive(Eq, PartialEq, Debug)]
pub enum IngressInductionError {
    /// Message enqueuing failed due to no matching canister ID.
    CanisterNotFound(CanisterId),

    /// Canister is stopped, not accepting any messages.
    CanisterStopped(CanisterId),

    /// Canister is stopping, only accepting responses.
    CanisterStopping(CanisterId),

    /// Canister is out of cycles.
    CanisterOutOfCycles(CanisterOutOfCyclesError),

    /// Message enqueuing failed due to calling an unknown subnet method.
    CanisterMethodNotFound(String),

    /// Message enqueuing failed due to calling a subnet method that is not
    /// allowed to be called via ingress messages.
    SubnetMethodNotAllowed(String),

    /// Message enqueuing failed due to calling a subnet method with
    /// an invalid payload.
    InvalidManagementPayload,

    /// Message enqueuing failed due to full ingress history.
    IngressHistoryFull { capacity: usize },
}

impl IngressInductionError {
    /// Returns a string representation of the `IngressInductionError` variant name to be
    /// used as a metric label value (e.g. `"InvalidSubnetPayload"`).
    pub fn to_label_value(&self) -> &'static str {
        match self {
            IngressInductionError::CanisterNotFound(_) => LABEL_VALUE_CANISTER_NOT_FOUND,
            IngressInductionError::CanisterStopped(_) => LABEL_VALUE_CANISTER_STOPPED,
            IngressInductionError::CanisterStopping(_) => LABEL_VALUE_CANISTER_STOPPING,
            IngressInductionError::CanisterOutOfCycles(_) => LABEL_VALUE_CANISTER_OUT_OF_CYCLES,
            IngressInductionError::CanisterMethodNotFound(_) => {
                LABEL_VALUE_CANISTER_METHOD_NOT_FOUND
            }
            IngressInductionError::SubnetMethodNotAllowed(_) => {
                LABEL_VALUE_SUBNET_METHOD_NOT_ALLOWED
            }
            IngressInductionError::InvalidManagementPayload => {
                LABEL_VALUE_INVALID_MANAGEMENT_PAYLOAD
            }
            IngressInductionError::IngressHistoryFull { .. } => LABEL_VALUE_INGRESS_HISTORY_FULL,
        }
    }
}

impl std::error::Error for IngressInductionError {}

impl std::fmt::Display for IngressInductionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngressInductionError::CanisterNotFound(canister_id) => {
                write!(f, "Canister {canister_id} not found")
            }
            IngressInductionError::CanisterStopped(canister_id) => {
                write!(f, "Canister {canister_id} is stopped")
            }
            IngressInductionError::CanisterStopping(canister_id) => {
                write!(f, "Canister {canister_id} is stopping")
            }
            IngressInductionError::CanisterOutOfCycles(err) => write!(f, "{err}"),
            IngressInductionError::CanisterMethodNotFound(method) => write!(
                f,
                "Cannot enqueue management message because {method} method is unknown."
            ),
            IngressInductionError::SubnetMethodNotAllowed(method) => write!(
                f,
                "Cannot enqueue management message because {method} method is not allowed to be called via ingress messages."
            ),
            IngressInductionError::InvalidManagementPayload => write!(
                f,
                "Cannot enqueue management message because its Candid payload is invalid."
            ),
            IngressInductionError::IngressHistoryFull { capacity } => {
                write!(f, "Maximum ingress history capacity {capacity} reached")
            }
        }
    }
}

impl From<&IngressInductionError> for ErrorCode {
    fn from(err: &IngressInductionError) -> Self {
        match err {
            IngressInductionError::CanisterNotFound(_) => ErrorCode::CanisterNotFound,
            IngressInductionError::CanisterStopped(_) => ErrorCode::CanisterStopped,
            IngressInductionError::CanisterStopping(_) => ErrorCode::CanisterStopping,
            IngressInductionError::CanisterOutOfCycles { .. } => ErrorCode::CanisterOutOfCycles,
            IngressInductionError::CanisterMethodNotFound(_) => ErrorCode::CanisterMethodNotFound,
            IngressInductionError::SubnetMethodNotAllowed(_) => ErrorCode::CanisterRejectedMessage,
            IngressInductionError::InvalidManagementPayload => ErrorCode::InvalidManagementPayload,
            IngressInductionError::IngressHistoryFull { .. } => ErrorCode::IngressHistoryFull,
        }
    }
}
