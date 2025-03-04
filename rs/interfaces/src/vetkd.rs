use ic_interfaces_state_manager::StateManagerError;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_types::{
    batch::VetKdAgreement, crypto::vetkd::VetKdKeyVerificationError, messages::CallbackId,
    registry::RegistryClientError, Height,
};

#[derive(Debug)]
pub enum InvalidVetKdPayloadReason {
    /// The feature is not enabled
    Disabled,
    /// The payload could not be deserialized
    DeserializationFailed(ProxyDecodeError),
    /// The payload contained a response that was already delivered
    DuplicateResponse(CallbackId),
    /// The payload contained a response that wasn't requested
    MissingContext(CallbackId),
    /// The payload contained a response for an IDkg context
    UnexpectedIDkgContext(CallbackId),
    /// The payload proposes the wrong type of agreement for a request context. For instance, the
    /// payload rejected a request that should have been accepted or vice versa.
    MismatchedAgreement {
        expected: Option<VetKdAgreement>,
        received: Option<VetKdAgreement>,
    },
    /// A success response couldn't be decoded
    DecodingError(String),
    /// A success response was cryptographically invalid
    VetKdKeyVerificationError(VetKdKeyVerificationError),
}

#[derive(Debug)]
pub enum VetKdPayloadValidationFailure {
    /// The state was not available for a height
    StateUnavailable(StateManagerError),
    /// The registry version was not available for a height
    RegistryVersionUnavailable(Height),
    /// The registry client returned an error
    RegistryClientError(RegistryClientError),
    /// Crypto failed to determine the validity of the key
    VetKdKeyVerificationError(VetKdKeyVerificationError),
}
